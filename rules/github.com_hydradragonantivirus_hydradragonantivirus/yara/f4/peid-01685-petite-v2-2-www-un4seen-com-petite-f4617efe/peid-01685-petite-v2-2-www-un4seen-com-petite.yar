rule PEiD_01685_Petite_v2_2____www_un4seen_com_petite_ {
  meta:
    description = "[Petite v2.2 -> www.un4seen.com/petite]"
    ep_only     = "false"

  strings:
    $a = { B8 00 ?0 4? 00 6? 00 ?? ?? 0? ?? ?? ?? ?? ?? 00 00 }

  condition:
    $a
}