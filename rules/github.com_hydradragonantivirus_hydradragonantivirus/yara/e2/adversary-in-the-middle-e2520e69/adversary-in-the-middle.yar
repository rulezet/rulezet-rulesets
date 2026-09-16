rule Adversary_in_the_Middle {
  meta:
    mitre = "T1557 Adversary in the Middle"

  strings:
    $a = "mitmproxy"
    $A = "mitmproxy" base64

  condition:
    any of them
}