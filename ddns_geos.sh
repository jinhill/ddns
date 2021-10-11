#! /bin/sh
#######################################################
# DDNS for GeoScaling DNS2
# Copyright: Jinhill 2021
# Depend on: curl jq openssl
# GEOS DNS: https://www.geoscaling.com
# Git repo: https://github.com/jinhill/ddns
#######################################################

VERSION="1.0.0"
ACCESS_KEY_ID="YOUR_KEY_ID"
ACCESS_KEY_SECRET="YOUR_KEY_SECRET"
DNS_NAME="ddns.yourdomain.com"
IP_SOURCE=0
IP_TYPE=""
DNS_SERVER="223.5.5.5"
COOKIE_FILE="/tmp/.ddns_geos.cookie"
SESSION_TIMEOUT=300
USER_AGENT='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36'
alias _CURL='curl -s --connect-timeout 10 -c ${COOKIE_FILE} -b ${COOKIE_FILE} -H "user-agent: $USER_AGENT" -H "accept: text/html;*/*"'
GET_IP_URL="https://icanhazip.com https://www.trackip.net/ip https://myip.wtf/text"
CRON_CMD="/sbin/ddns_geos.sh -d"
STATUS="good nochg nohost abuse notfqdn badauth 911 badagent badresolv badconn"
LOG_LEVEL=2

#ERROR-0,WARN-1,INFO-2,DEBUG-3
#$1:level $2:string
log(){
  [ "$1" -le ${LOG_LEVEL} ] && printf "[%s]: %s\n" >&2 "$(date +'%Y-%m-%d %H:%M:%S')" "$2"
}

#$1:string,$2:char, if $2 not set return array len,$ret:count
count() {
  if [ -n "$2" ];then
    echo "$1" | awk -F"$2" '{print NF-1}'
  else
    echo "$1" | wc -w
  fi
}

#$1:array data,$2:idx
get_idx_item(){
  echo "$1" | tr ' ' '\n' | sed '/^$/d' | sed -n "$2p"
}

#$1:domain,$2:ip type 4/6,$3:dns server
get_dns(){
  #need dnsutils
  resolve_cmd=nslookup
  head_line=3
  regex_str="[a-f0-9:.]{7,}$"
  if [ -x "$(command -v host)" ];then
    #debain
    resolve_cmd=host
    if [ -z "$3" ];then
      head_line=1
    fi
  fi
  if [ "$2" = "4" ];then
    regex_str="[0-9.]{7,}$"
  elif [ "$2" = "6" ];then
    regex_str="[a-f0-9:]{7,}$"
  fi
  $resolve_cmd "$1" $3 | tail -n +$head_line | grep -ioE "${regex_str}"
}

#$1:4/6,if not set return all wan ips, ret:wan ip
get_wan_ip(){
  ips=""
  for url in ${GET_IP_URL}; do
    if [ -z "$1" ];then
      ip4=$(_CURL -4 "${url}")
      ip6=$(_CURL -6 "${url}")
      ips="${ip4} ${ip6}"
    else
      ips=$(_CURL -"$1" "${url}")
    fi
    ips=$(echo "$ips" | sed -e 's/^[ ]*//g'  -e 's/[ ]*$//g')
    if [ -n "${ips}" ];then
      break
    fi
  done
  echo "${ips}"
}

#$1:interface-eth0/all,$2:4/6-(ipv4/ipv6),else-ipv4 & ipv6
get_local_ip(){
  nif=$1
  v=$2
  if [ "$nif" = "all" ];then
    nif=""
  fi
  if [ "$v" = "4" ];then
    v=""
  elif [ "$v" = "6" ];then
    v="6"
  else
    v="6\?"
  fi
  #exclude private IP address ranges
  # ip a s $nif |sed -ne "/192.168\|172.16\|10./! {s/^[ \t]*inet${v}[ \t]*\([0-9a-fA-F.:]\{7,\}\).*scope global.*/\1/p}"
  ip a s $nif | sed -ne "s/^[ \t]*inet${v}[ \t]*\([0-9a-fA-F.:]\{7,\}\).*scope global.*/\1/p"
}

#$1:domain,$2:real_ips,$3:ip_type-4/6,$ret:0-dns is valid,1-dns is invalid
check_dns(){
  ips=$(get_dns "$1" "$3" "${DNS_SERVER}")
  ips=$(echo "${ips}" | tr ' ' '\n' | sort | sed '/^$/d')
  real_ips=$(echo "$2" | tr ' ' '\n' | sort | sed '/^$/d')
  if [ "${ips}" = "${real_ips}" ]; then
    echo 0
  else
    echo 1
  fi
}

#$1:url
url_encode() {
  echo "$1" | awk -v ORS="" '{ gsub(/./,"&\n") ; print }' | while read -r l;
  do
    case "$l" in
      [-_.~a-zA-Z0-9] ) printf '%s' "$l" ;;
      "" ) printf '%%20' ;;
      * )  printf '%%%02X' "'$l"
    esac
  done
}

#$1:dns value
detect_type(){
  type="TXT"
  if echo "$1" | grep -iqE '[a-f0-9:]{7,}$' ;then
    type="AAAA"
  elif echo "$1" | grep -iqE '[0-9.]{7,}$' ;then
    type="A"
  elif echo "$1" | grep -iqE '^\w+([-.]?\w+)*.[a-z]{2,}$' ;then
    type="CNAME"
  fi
  echo "${type}"
}

# $1:full domain,$2:domain list with id
# ret:[id,root domain]
get_root_domain(){
  c=$(count "$1" ".")
  i=$c
  ds=$(echo "$2" | tr ' ' '\n')
  while [ "$i" -gt 0 ]; do
    d=$(echo "$1" | cut -d '.' -f "$i"-)
    if [ -z "$d" ]; then
      return 4
    fi
    #without id in $2
    #q=$( echo "${ds}" | grep -oE "^$d$")
    q=$( echo "${ds}" | grep -E ",$d$")
    if [ -n "$q" ];then
      echo "$q"
      return 0
    fi
    i=$(( i - 1 ))
  done
  return 2
}

################ GeoScaling Private Functions ################
#$1:seesion mode,$2:username,$3:password
login() {
  if [ -n "$1" ] && [ "$1" = "1" ] && [ -f "${COOKIE_FILE}" ];then
    c_t=$(date -r "${COOKIE_FILE}"  "+%s")
    now=$(date "+%s")
    s_t=$(( now - c_t ))
    if [ "${s_t}" -lt ${SESSION_TIMEOUT} ];then
      return 0
    fi
  fi

  GEOS_Username="${2:-$ACCESS_KEY_ID}"
  GEOS_Password="${3:-$ACCESS_KEY_SECRET}"
  if [ -z "${GEOS_Username}" ] || [ -z "${GEOS_Password}" ]; then
    GEOS_Username=
    GEOS_Password=
    log 0 "No auth details provided. Please set user credentials using the \$ACCESS_KEY_ID and \$ACCESS_KEY_SECRET environment variables."
    return 1
  fi
  enc_username=$(url_encode "${GEOS_Username}")
  enc_password=$(url_encode "${GEOS_Password}")
  body="username=${enc_username}&password=${enc_password}"
  http_code=$(_CURL -X POST -d "$body" -o /dev/null -w "%{http_code}" "https://www.geoscaling.com/dns2/index.php?module=auth")
  if [ "${http_code}" = "302" ]; then
    return 0
  fi
  log 0 "Geoscaling login failed for user ${GEOS_Username} bad RC from post"
  return 1
}

#ret:[id,domain] list
get_domain(){
  resp=$(_CURL "https://www.geoscaling.com/dns2/index.php?module=domains")
  table=$(echo "${resp}" | grep -oE "<table[^>]+ class=\"threecolumns\">.*</table>")
  items=$(echo "${table}" | grep -oE '<a [^>]+><b>[^>]+>')
  echo "${items}" | sed -nr 's/.*id=([0-9]+).*<b>(.*)<\/b>/\1,\2/p'
}
#$1:domain id,$2:dns fullname
get_dns_id() {
  resp=$(_CURL "https://www.geoscaling.com/dns2/index.php?module=domain&id=$1")
  ids=$(echo "${resp}" | tr -d "\n" | grep -oE "<table id='records_table'.*</a></td></tr></table>" | grep -oE "id=\"[0-9]*.name\">$2" | cut -d '"' -f 2 | cut -d '.' -f 1)
  if [ -z "${ids}" ]; then
    log 1 "DNS record $2 not found."
    return 1
  fi
  echo "${ids}"
  return 0
}

#$1:domain id,$2:dns fullname
get_smart_dns_id() {
  resp=$(_CURL "https://www.geoscaling.com/dns2/index.php?module=smart_subdomains&id=$1")
  id=$(echo "${resp}" | tr -d "\n" | grep -oiE "<a href=\"index.php\?module=smart_subdomain[^>]+>[a-z.]*</a>" | grep -oE "subdomain_id=[0-9]*\">$2" | cut -d '=' -f 2 | cut -d '"' -f 1)
  if [ -z "${id}" ]; then
    log 1 "DNS record $2 not found."
    return 1
  fi
  echo "${id}"
  return 0
}

#$1:username,$2:password,$3:full domain,$4:type,$5:value array,$ret:0-success,else-failed
add_dns(){
  full_domain=$3
  type=$4
  value=$5
  rv=0
  login 1 "$1" "$2" || return 1
  domains=$(get_domain)
  root_domain_info=$(get_root_domain "${full_domain}" "${domains}")
  if [ -z "${root_domain_info}" ];then
    log 0 "The hostname [${full_domain}] does not exist in this user account."
    return 2
  fi
  domain_id="${root_domain_info%%,*}"
  sub_domain=$(echo "${full_domain}" | sed "s/\.\?${root_domain_info##*,}//")
  for value in $5; do
    [ -n "${type}" ] || type=$(detect_type "${value}")
    body="id=${domain_id}&name=${sub_domain}&type=${type}&content=${value}&ttl=300&prio=0"
    resp=$(_CURL -X POST -d "$body" "https://www.geoscaling.com/dns2/ajax/add_record.php")
    if echo "${resp}" | grep -q '"code":"OK"'; then
      log 2 "The DNS record [${full_domain}: ${value}] has been added successfully."
    else
      log 0 "Failed to add dns [${full_domain}: ${value}]."
      rv=4
    fi
  done
  echo ${rv}
}

#$1:username,$2:password,$3:host name,$4:DNS RecordId array,$ret:0-success,else-failed
del_dns(){
  rv=0
  login 1 "$1" "$2" || return 1
  domains=$(get_domain)
  root_domain_info=$(get_root_domain "$3" "${domains}")
  if [ -z "${root_domain_info}" ];then
    log 0 "The hostname [${full_domain}] does not exist in this user account."
    return 2
  fi
  domain_id="${root_domain_info%%,*}"
  rids="$4"
  [ -n "$4" ] || rids=$(get_dns_id "${domain_id}" "${name}")
  for rid in ${rids}; do
    body="id=${domain_id}&record_id=${rid}"
    resp=$(_CURL -X POST -d "$body" "https://www.geoscaling.com/dns2/ajax/delete_record.php")
    if echo "${resp}" | grep -q '"code":"OK"'; then
      log 2 "The DNS record [$3:$rid] has been deleted successfully."
    else
      rv=2
      log 0 "Could not delete the record [$3:$rid]. Please go to geoscaling.com and clean it by hand."
    fi
   done
  echo ${rv}
}

#$1:username,$2:password,$3:full domain,$4:type,$5:value array,$ret:0-success,else-failed
update_dns(){
  rv=0
  if [ -z "$3" ] || [ -z "$5" ];then
    return 1
  fi
  full_domain=$3
  login 1 "$1" "$2" || return 1
  domains=$(get_domain)
  root_domain_info=$(get_root_domain "${full_domain}" "${domains}")
  if [ -z "${root_domain_info}" ];then
    log 0 "The hostname [${full_domain}] does not exist in this user account."
    return 2
  fi
  domain_id="${root_domain_info%%,*}"
  rids=$(get_dns_id "${domain_id}" "${full_domain}")
  v_cnt=$(count "$5")
  #del & add it with a multi IPs
  if [ -z "${rids}" ] || [ "${v_cnt}" -gt 1 ];then
    if [ -n "${rids}" ];then
      rv=$(del_dns "$1" "$2" "${full_domain}" "${rids}")
    fi
    add_dns "$@"
    return
  fi
  #Update it with a single IP
  if [ -z "$4" ];then
    dns_type=$(detect_type "$5")
  fi
   rid="${rids}"
  #update dns type
  body="value=${dns_type}&id=${rid}.type"
  resp=$(_CURL -X POST -d "$body" "https://www.geoscaling.com/dns2/ajax/edit_record.php")
  #update dns content
  body="value=$5&id=${rid}.content"
  resp=$(_CURL -X POST -d "$body" "https://www.geoscaling.com/dns2/ajax/edit_record.php")
  if [ "${resp}" == "$5" ];then
    log 2 "The DNS record [$3: $5] has been updated successfully."
  else
    rv=3
    log 0 "Failed to update dns [$3: $5]."
  fi
  echo ${rv}
}

#$1:username,$2:password,$3:full domain,$4:value array
update_smartdns() {
  rv=0
  if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ];then
    echo 2
    return 2
  fi
  full_domain=$3
  value=$(echo "$4" | tr ' ' '\n' | sed '/^$/d')
  login 1 "$1" "$2" || return 1
  domains=$(get_domain)
  root_domain_info=$(get_root_domain "${full_domain}" "${domains}")
  if [ -z "${root_domain_info}" ];then
    log 0 "The hostname [${full_domain}] does not exist in this user account."
    echo 2
    return 2
  fi
  domain_id="${root_domain_info%%,*}"
  sub_domain=$(echo "${full_domain}" | sed "s/\.\?${root_domain_info##*,}//")
  rid=$(get_smart_dns_id "${domain_id}" "${full_domain}") || return 1
  ip_value=$(echo "${value}" | grep -ioE '[a-f0-9:.]{7,}$')
  cname_value=$(echo "${value}" | grep -ioE '^\w+([-.]?\w+)*.[a-z]{2,}$')
  ip_list="";
  for ip in ${ip_value}; do
  	ip_type=$(detect_type "${ip}")
    ip_list="${ip_list}  \$output[] = array(\"${ip_type}\", \"${ip}\", \"300\");\r\n"
  done
  code='if($country == "cn"){\r\n'"${ip_list}"'}\r\nelse{\r\n  $output[] = array("CNAME", "'"${cname_value}"'");\r\n}'
  rand=$(tr -dc "0123456789abcdefABCDEF" < "/dev/urandom" | head -c16)
  boundary="----WebKitFormBoundary${rand}"
  body=$'{{BOUNDARY}}\r\nContent-Disposition: form-data; name="MAX_FILE_SIZE"\r\n\r\n65536\r\n{{BOUNDARY}}\r\nContent-Disposition: form-data; name="name"\r\n\r\n{{HOST}}\r\n{{BOUNDARY}}\r\nContent-Disposition: form-data; name="sharecountry_info"\r\n\r\non\r\n{{BOUNDARY}}\r\nContent-Disposition: form-data; name="failsafe_ip"\r\n\r\n\r\n{{BOUNDARY}}\r\nContent-Disposition: form-data; name="code"\r\n\r\n{{CODE}}\r\n{{BOUNDARY}}--\r\n'
  body=$(echo "$body"| sed -e "s/{{BOUNDARY}}/--${boundary}/g;s/{{HOST}}/${sub_domain}/g;s/{{CODE}}/${code}/g")
  resp=$(_CURL -X POST "https://www.geoscaling.com/dns2/index.php?module=smart_subdomain&id=${domain_id}&subdomain_id=${rid}" \
    -H "content-type: multipart/form-data; boundary=${boundary}" \
    -H "accept: */*" \
    --data-raw "${body}")
  ip_regex=$(echo "${ip_value}" | sed -e "s/ /\|/g")
  ip_c=$(count "${ip_value}")
  mc=$(echo "${resp}" | grep -cE "${ip_regex}")
  if [ "$ip_c" = "$mc" ];then
    log 2 "The smartdns record [${full_domain}] has been updated successfully."
  else
    log 0 "Failed to update smartdns [${full_domain}]."
    rv=9
  fi
  echo ${rv}
}

################ GeoScaling Private Functions end ################

#$1:username,$2:password,$3:full domain,$4:0-wan 1-local,$5:ipv4/6
detect_update(){
  rv=0
  if [ "$4" = "1" ]; then
    real_ips=$(get_local_ip "all" "$5")
    if [ "$5" = 6 ];then
      real_ips=$(echo "${real_ips}" | head -n 1)
    fi
  else
    real_ips=$(get_wan_ip "$5")
  fi
  if [ -z "${real_ips}" ]; then
    log 0 "Error! can not get ip."
    echo "3"
    return 3
  fi
  update_flag=$(check_dns "$3" "${real_ips}" "$5")
  if [ "${update_flag}" = "1" ]; then
    dns_type=""
    if [ "$5" = "4" ];then
      dns_type="A"
    elif [ "$5" = "6" ];then
      dns_type="AAAA"
    fi
    rv=$(update_dns "$1" "$2" "$3" "${dns_type}" "${real_ips}")
  else
    rv=1
  fi
  echo ${rv}
}

install(){
  pkg_cmd=apt
  pkg_ssl=openssl
  restart_cmd="systemctl restart cron"
  if [ -x "$(command -v opkg)" ];then
    pkg_cmd=opkg
    pkg_ssl=openssl-util
    restart_cmd="/etc/init.d/cron restart"
  elif [ -x "$(command -v yum)" ];then
    pkg_cmd=yum
    restart_cmd="systemctl restart crond"
  fi
  if [ -x "$(command -v curl)" ] && [ -x "$(command -v jq)" ] && [ -x "$(command -v openssl)" ]; then
    log 2 "Check dependency package(curl,jq,openssl): passed."
  else
    $pkg_cmd update && $pkg_cmd install curl jq $pkg_ssl
  fi
  cp "$0"  /sbin/
  chmod +x  /sbin/ddns_ali.sh
  ( crontab -l | grep -v -F "$CRON_CMD" ; echo "*/5 * * * * $CRON_CMD" ) | crontab -
  $restart_cmd
  log 2 "ddns server is installed."
  exit
}

uninstall(){
  ( crontab -l | grep -v -F "$CRON_CMD" ) | crontab -
  rm -rf /sbin/ddns_ali.sh
  log 2 "ddns server is removed."
  exit
}

help()
{
  printf "%s ver:%s\nUsage:\n" "$0" "$VERSION"
  printf "%s [-46adhmur] [-i <key id>] [-s <key secret>] [-n <dns name>] [-l <ip source>] [-t <dns type>] [-v <dns value arrays>]\n" "$0"
  printf "%s --install/uninstall\n" "$0"
  printf "only for Synology DSM ddns:\n"
  printf "%s <key id> <key secret> <dns name>\n" "$0"
  printf "\t-4/6 get ipv4/6;\n"
  printf "\t-a add dns;\n"
  printf "\t-d auto detect ip and update;\n"
  printf "\t-i set key id;\n"
  printf "\t-l <0/1> set ip source, 0-wan ip, 1-local ip;\n"
  printf "\t-m update smartdns;\n"
  printf "\t-n set dns name;\n"
  printf "\t-u update dns;\n"
  printf "\t-r remove dns;\n"
  printf "\t-s set key secret;\n"
  printf "\t-t set dns type;\n"
  printf "\t-v set dns value arrays;\n"
  printf "\t--install/uninstall install/uninstall this script;\n"
  printf "\t-h Print help.\n"
  exit 1
}

main(){
  rv=0
  opt_type=0
  while getopts "i:l:n:t:v:s:-:46adhmur" opt; do
    case "${opt}" in
      4 | 6 ) ip_type=${opt} ;;
      a ) act=1 ;;
      d ) act=3 ;;
      i ) key_id="${OPTARG}" ;;
      l ) ip_source=${OPTARG} ;;
      m ) act=5 ;;
      n ) name="${OPTARG}" ;;
      t ) type="${OPTARG}" ;;
      u ) act=2 ;;
      v ) value="${OPTARG}" ;;
      r ) act=0 ;;
      s ) key_secret="${OPTARG}" ;;
      - ) case "${OPTARG}" in
          install ) install ;;
          uninstall ) uninstall ;;
          *) log 0 "Unknown option --${OPTARG}"
            help
          ;;
        esac ;;
      h | ? ) help ;;
    esac
    opt_type=1
  done
  # Adapt to Synology DSM
  if [ "${opt_type}" = 0 ] && [ -n "$*" ];then
    key_id="$1"
    key_secret="$2"
    name="$3"
    act=4
  fi
  key_id=${key_id:-${ACCESS_KEY_ID}}
  key_secret=${key_secret:-${ACCESS_KEY_SECRET}}
  name=${name:-${DNS_NAME}}
  ip_source=${ip_source:-${IP_SOURCE}}
  ip_type=${ip_type:-${IP_TYPE}}
  
  case "${act}" in
    0 )
      rv=$(del_dns "${key_id}" "${key_secret}" "${name}" "${rids}")
      ;;
    1 )
      rv=$(add_dns "${key_id}" "${key_secret}" "${name}" "${type}" "${value}")
      ;;
    2 )
      rv=$(update_dns "${key_id}" "${key_secret}" "${name}" "${type}" "${value}")
      ;;
    3 | 4 )
      rv=$(detect_update "${key_id}" "${key_secret}" "${name}" "${ip_source}" "${ip_type}")
      if [ "${act}" = 4 ];then
        echo "${STATUS}" | cut -d ' ' -f$((rv+1))
      fi
      ;;
    5 )
      rv=$(update_smartdns "${key_id}" "${key_secret}" "${name}" "${value}")
  esac
  exit ${rv}
}

main "$@"