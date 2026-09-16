rule NewManager {
  meta:
    copyright = "Intezer Labs"
    author    = "Intezer Labs"
    reference = "https://www.intezer.com"

  strings:
    $a0 = { 8B ?? 04 3? 03 00 00 11 74 4D 3? 11 00 00 11 74 61 3? 02 00 00 11 }
    $b0 = "_ConnectServer"
    $b1 = "/root/1/ampS.log"
    $b2 = "/etc/rc%d.d/S%d%s"
    $b3 = "Get SYstem Info"
    $b4 = "newmanager"
    $b5 = "NO DDXC"

  condition:
    all of them
}