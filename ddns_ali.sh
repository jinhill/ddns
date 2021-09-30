#! /bin/sh
#
# DDNS for Aliyun
# Copyright: Jinhill 2021
# Depend on: curl jq openssl

VERSION="1.0.0"
ACCESS_KEY_ID="YOUR_KEY_ID"
ACCESS_KEY_SECRET="YOUR_KEY_SECRET"
DNS_NAME="ddns.yourdomain.com"
IP_SOURCE=0
IP_TYPE=""
DNS_SERVER="223.5.5.5"
_CURL='curl -s --connect-timeout 10'
GET_IP_URL="https://icanhazip.com https://www.trackip.net/ip https://myip.wtf/text"
ALIDNS_URL="http://alidns.aliyuncs.com/"
CRON_CMD="/sbin/ddns_ali.sh -d"
STATUS="good nochg nohost abuse notfqdn badauth 911 badagent badresolv badconn"

log(){
  printf "[%s]: %s\n" >&2 "$(date +'%Y-%m-%d %H:%M:%S')" "$*"
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
  if [ $(command -v host) ];then
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
      ip4=$($_CURL -4 "${url}")
      ip6=$($_CURL -6 "${url}")
      ips="${ip4} ${ip6}"
    else
      ips=$($_CURL -$1 "${url}")
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

#$1:host,$2:port
check_connect(){
  nc -z "$1" "$2"
  echo "$?"
}

#$1:url
url_encode() {
  echo "$1" | awk -v ORS="" '{ gsub(/./,"&\n") ; print }' | while read -r l
  do
    case "$l" in
      [-_.~a-zA-Z0-9] ) echo -n ${l} ;;
      "" ) echo -n %20 ;;
      * )  printf '%%%02X' "'$l" ;;
    esac
  done
}

#$1:dns value
detect_type(){
  type="TXT"
  if [ $(echo "$1" | grep -ioE '[a-f0-9:]{7,}$') ];then
    type="AAAA"
  elif [ $(echo "$1" | grep -ioE '[0-9.]{7,}$') ];then
    type="A"
  elif [ $(echo "$1" | grep -ioE '^\w+([-.]?\w+)*.[a-z]{2,}$') ];then
    type="CNAME"
  fi
  echo "$type"
}

#$1:ACCESS_KEY_SECRET,$2:data
sign_data(){
  enc_str=$(url_encode "$2")
  data="GET&%2F&${enc_str}"
  sign=$(echo -n "${data}" | openssl dgst -binary -sha1 -hmac "$1&" | openssl base64)
  url_encode "$sign"
}

#$1:full domain,$2:Aliyun domain list
get_root_domain(){
  c=$(count "$1" ".")
  i=$c
  ds=$(echo "$2" | tr ' ' '\n')
  while [ $i -gt 0 ]; do
    d=$(echo "$1" | cut -d '.' -f $i-)
    if [ -z "$d" ]; then
      return 4
    fi
    q=$( echo "$ds" | grep -oE "^$d$")
    if [ -n "$q" ];then
      echo "$d"
      return
    fi
    i=$(( i - 1 ))
  done
  return 2
}

#$1:AccessKeyId,$2:AccessKeySecret
get_domain(){
  nonce=$(date +%s%N)
  timestamp=$(date -u "+%Y-%m-%dT%H%%3A%M%%3A%SZ")
  params="AccessKeyId=$1&Action=DescribeDomains&Format=JSON&SignatureMethod=HMAC-SHA1&SignatureNonce=${nonce}&SignatureVersion=1.0&Timestamp=${timestamp}&Version=2015-01-09"
  sign=$(sign_data "$2" "${params}")
  req_url="${ALIDNS_URL}?${params}&Signature=${sign}"
  resp=$($_CURL "$req_url")
  if echo "$resp" | grep -iqE "InvalidAccessKeyId|SignatureDoesNotMatchA";then
    return 5
  elif echo "$resp" | grep -iqE "Message";then
    return 9
  else
    echo "$resp" | jq -r ".Domains.Domain | .[].DomainName"
  fi
}

#$1:AccessKeyId,$2:AccessKeySecret,$3:DomainName,$4:RRKeyWord,$5:TypeKeyWord
query_dns(){
  nonce=$(date +%s%N)
  timestamp=$(date -u "+%Y-%m-%dT%H%%3A%M%%3A%SZ")
  if [ -n "$5" ];then
    dns_type_param="&TypeKeyWord=$5"
  fi
  params="AccessKeyId=$1&Action=DescribeDomainRecords&DomainName=$3&Format=JSON&RRKeyWord=$4&SignatureMethod=HMAC-SHA1&SignatureNonce=${nonce}&SignatureVersion=1.0&Timestamp=${timestamp}${dns_type_param}&Version=2015-01-09"
  sign=$(sign_data "$2" "${params}")
  req_url="${ALIDNS_URL}?${params}&Signature=${sign}"
  $_CURL "$req_url"
}

#$1:AccessKeyId,$2:AccessKeySecret,$3:DomainName,$4:RRKeyWord,$5:TypeKeyWord
get_dns_ids(){
  resp=$(query_dns "$@")
  echo "$resp" | jq -r ".DomainRecords.Record | map(select(.RR = \"$4\")) | .[].RecordId"
}

#$1:AccessKeyId,$2:AccessKeySecret,$3:DomainName,$4:RR,$5:type,$6:value array,$ret:0-success,else-failed
add_dns(){
  rv=0
  dns_type="$5"
  for value in $6; do
    if [ -z "$5" ];then
      dns_type=$(detect_type "${value}")
    fi
    nonce=$(date +%s%N)
    timestamp=$(date -u "+%Y-%m-%dT%H%%3A%M%%3A%SZ")
    enc_value=$(url_encode "${value}")
    params="AccessKeyId=$1&Action=AddDomainRecord&DomainName=$3&Format=JSON&Line=default&RR=$4&SignatureMethod=HMAC-SHA1&SignatureNonce=${nonce}&SignatureVersion=1.0&TTL=600&Timestamp=${timestamp}&Type=${dns_type}&Value=${enc_value}&Version=2015-01-09"
    sign=$(sign_data "$2" "${params}")
    req_url="${ALIDNS_URL}?${params}&Signature=${sign}"
    resp=$($_CURL "$req_url")
    rid=$(echo "$resp" | jq -r ".RecordId")
    if echo "$resp" | grep -qw "DomainRecordDuplicate";then
      rv=1
      log "The DNS record [$4.$3: ${value}] already exists."
    elif [ "${rid}" != "null" ];then
      log "The DNS record [$4.$3: ${value}] has been added successfully."
    else
      rv=4
      log "Failed to add dns [$4.$3: ${value}]."
    fi
  done
  echo ${rv}
}

#$1:AccessKeyId,$2:AccessKeySecret,$3:DNS RecordId array,$ret:0-success,else-failed
del_dns(){
  rv=0
  for rid in $3; do
    nonce=$(date +%s%N)
    timestamp=$(date -u "+%Y-%m-%dT%H%%3A%M%%3A%SZ")
    params="AccessKeyId=$1&Action=DeleteDomainRecord&Format=JSON&RecordId=${rid}&SignatureMethod=HMAC-SHA1&SignatureNonce=${nonce}&SignatureVersion=1.0&Timestamp=${timestamp}&Version=2015-01-09"
    sign=$(sign_data "$2" "${params}")
    req_url="${ALIDNS_URL}?${params}&Signature=${sign}"
    resp=$($_CURL "$req_url")
    rrid=$(echo "$resp" | jq -r ".RecordId");
    if [ "${rrid}" != "null" ];then
      log "The DNS record [$rid] has been deleted successfully."
    else
      rv=2
      log "Failed to delete dns [$rid}]."
    fi
  done
  echo ${rv}
}

#$1:AccessKeyId,$2:AccessKeySecret,$3:DomainName,$4:RR,$5:type,$6:value array,$ret:0-success,else-failed
update_dns(){
  rv=0
  rids=$(get_dns_ids "$1" "$2" "$3" "$4" "$5")
  v_cnt=$(count "$6")
  #del & add it with a multi IPs
  if [ -z "${rids}" ] || [ "${v_cnt}" -gt 1 ];then
    if [ -n "${rids}" ];then
      rv=$(del_dns "$1" "$2" "${rids}")
    fi
    add_dns "$@"
    return
  fi
  #Update it with a single IP
  if [ -z "$5" ];then
    dns_type=$(detect_type "$6")
  fi
  nonce=$(date +%s%N)
  timestamp=$(date -u "+%Y-%m-%dT%H%%3A%M%%3A%SZ")
  enc_value=$(url_encode "$6")
  params="AccessKeyId=$1&Action=UpdateDomainRecord&Format=JSON&Line=default&RR=$4&RecordId=${rids}&SignatureMethod=HMAC-SHA1&SignatureNonce=${nonce}&SignatureVersion=1.0&TTL=600&Timestamp=${timestamp}&Type=${dns_type}&Value=${enc_value}&Version=2015-01-09"
  sign=$(sign_data "$2" "${params}")
  req_url="${ALIDNS_URL}?${params}&Signature=${sign}"
  resp=$($_CURL "$req_url")
  #resp={"RecordId":"3152634241029120","RequestId":"5612CC91-1F30-46A0-84E8-43C0A4B7098A"}
  rid=$(echo "$resp" | jq -r ".RecordId");
  if echo "$resp" | grep -qw "DomainRecordDuplicate";then
    rv=1
    log "The DNS record [$4.$3: $6] already exists."
  elif [ "${rid}" != "null" ];then
    log "The DNS record [$4.$3: $6] has been updated successfully."
  else
    rv=3
    log "Failed to update dns [$4.$3: $6]."
  fi
  echo ${rv}
}

#$1:AccessKeyId,$2:AccessKeySecret,$3:DomainName,$4:RR,$5:0-wan 1-local,$6:ipv4/6
detect_update(){
  rv=0
  if [ "$5" = "1" ]; then
    real_ips=$(get_local_ip "all" $6)
    if [ "$6" = 6 ];then
      real_ips=$(echo "${real_ips}" | head -n 1)
    fi
  else
    real_ips=$(get_wan_ip $6)
  fi
  if [ -z "${real_ips}" ]; then
    log "Error! can not get ip."
    echo "3"
    return 3
  fi
  update_flag=$(check_dns "$4.$3" "${real_ips}" $6)
  if [ "${update_flag}" = "1" ]; then
    dns_type=""
    if [ "$6" = "4" ];then
      dns_type="A"
    elif [ "$6" = "6" ];then
      dns_type="AAAA"
    fi
    rv=$(update_dns "$1" "$2" "$3" "$4" "${dns_type}" "${real_ips}")
  else
    rv=1
  fi
  echo ${rv}
}

install(){
  pkg_cmd=apt
  pkg_ssl=openssl
  restart_cmd="systemctl restart cron"
  if [ $(command -v opkg) ];then
    pkg_cmd=opkg
    pkg_ssl=openssl-util
    restart_cmd="/etc/init.d/cron restart"
  elif [ $(command -v yum) ];then
    pkg_cmd=yum
    restart_cmd="systemctl restart crond"
  fi
  if [ $(command -v curl) ] && [ $(command -v jq) ] && [ $(command -v openssl) ]; then
    echo "Check dependency package(curl,jq,openssl): passed."
  else
    $pkg_cmd update && $pkg_cmd install curl jq $pkg_ssl
  fi
  cp "$0"  /sbin/
  chmod +x  /sbin/ddns_ali.sh
  ( crontab -l | grep -v -F "$CRON_CMD" ; echo "*/5 * * * * $CRON_CMD" ) | crontab -
  $restart_cmd
  echo "ddns server is installed."
  exit
}

uninstall(){
  ( crontab -l | grep -v -F "$CRON_CMD" ) | crontab -
  rm -rf /sbin/ddns_ali.sh
  echo "ddns server is removed."
  exit
}

help()
{
  printf "ddns_ali.sh ver:%s\nUsage:\n" "$VERSION"
  printf "$0 [-46adhur] [-i <key id>] [-s <key secret>] [-n <dns name>] [-l <ip source>] [-t <dns type>] [-v <dns value arrays>]\n"
  printf "$0 --install/uninstall\n"
  printf "only for Synology DSM ddns:\n"
  printf "$0 <key id> <key secret> <dns name>\n"
  printf "\t-4/6 get ipv4/6;\n"
  printf "\t-a add dns;\n"
  printf "\t-d auto detect ip and update;\n"
  printf "\t-i set key id;\n"
  printf "\t-l <0/1> set ip source, 0-wan ip, 1-local ip;\n"
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
  while getopts "i:l:n:t:v:s:-:46adhur" opt; do
    case "${opt}" in
      4 | 6 ) ip_type=${opt} ;;
      a ) act=1 ;;
      d ) act=3 ;;
      i ) key_id="${OPTARG}" ;;
      l ) ip_source=${OPTARG} ;;
      n ) name="${OPTARG}" ;;
      t ) type="${OPTARG}" ;;
      u ) act=2 ;;
      v ) value="${OPTARG}" ;;
      r ) act=0 ;;
      s ) key_secret="${OPTARG}" ;;
      - ) case "${OPTARG}" in
          install ) install ;;
          uninstall ) uninstall ;;
          *) log "Unknown option --${OPTARG}"
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

  if [ -n "${name}" ];then
    domains=$(get_domain "${key_id}" "${key_secret}")
    rv=$?
    if [ -z "${domains}" ];then
      if [ "${act}" = 4 ];then
        echo "${STATUS}" | cut -d ' ' -f$((rv+1))
      else
        log "Authentication failed."
      fi
      exit ${rv}
    fi

    root_domain=$(get_root_domain "${name}" "${domains}")
    rv=$?
    if [ ! ${rv} -eq 0 ];then
      if [ "${act}" = 4 ];then
        echo "${STATUS}" | cut -d ' ' -f$((rv+1))
      else
        log "The hostname [${name}] does not exist in this user account."
      fi
      exit ${rv}
    fi

    rr=${name%%".${root_domain}"*}
  fi
  
  case "${act}" in
    0 )
      rids=$(get_dns_ids "${key_id}" "${key_secret}" "${root_domain}" "${rr}" "${type}")
      if [ -n "${rids}" ];then
        rv=$(del_dns "${key_id}" "${key_secret}" "${rids}")
      fi
      ;;
    1 )
      rv=$(add_dns "${key_id}" "${key_secret}" "${root_domain}" "${rr}" "${type}" "${value}")
      ;;
    2 )
      rv=$(update_dns "${key_id}" "${key_secret}" "${root_domain}" "${rr}" "${type}" "${value}")
      ;;
    3 | 4 )
      rv=$(detect_update "${key_id}" "${key_secret}" "${root_domain}" "${rr}" "${ip_source}" "${ip_type}")
      if [ "${act}" = 4 ];then
        echo "${STATUS}" | cut -d ' ' -f$((rv+1))
      fi
      ;;
  esac
  exit ${rv}
}

main "$@"