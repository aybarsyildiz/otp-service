/system scheduler
remove [find name=olives-dns-log]
add interval=2m name=olives-dns-log on-event={
:local logToken "olives-admin-2024"
:foreach user in=[/ip hotspot active find] do={
  :local userPhone [/ip hotspot active get $user user]
  :local userMac [/ip hotspot active get $user mac-address]
  :local userIp [/ip hotspot active get $user address]
  :foreach entry in=[/ip dns cache find where dynamic=yes] do={
    :local domain [/ip dns cache get $entry name]
    :if ([:len $domain] > 0) do={
      :do {
        /tool fetch url="http://52.57.199.152:3000/log/dns" mode=http http-method=post http-header-field="Content-Type: application/json,x-log-token: olives-admin-2024" http-data=("{\"phone\":\"" . $userPhone . "\",\"mac\":\"" . $userMac . "\",\"ip\":\"" . $userIp . "\",\"domain\":\"" . $domain . "\"}") keep-result=no
      } on-error={}
    }
  }
}
}
