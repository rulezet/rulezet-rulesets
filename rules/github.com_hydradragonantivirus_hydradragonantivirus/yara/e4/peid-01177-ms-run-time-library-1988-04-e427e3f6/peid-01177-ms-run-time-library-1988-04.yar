rule PEiD_01177_MS_Run_Time_Library_1988__04__ {
  meta:
    description = "[MS Run-Time Library 1988 (04)]"
    ep_only     = "true"

  strings:
    $a = { 1E B8 ?? ?? 8E D8 B4 30 CD 21 3C 02 73 ?? BA ?? ?? E8 ?? ?? 06 33 C0 50 CB }

  condition:
    $a
}