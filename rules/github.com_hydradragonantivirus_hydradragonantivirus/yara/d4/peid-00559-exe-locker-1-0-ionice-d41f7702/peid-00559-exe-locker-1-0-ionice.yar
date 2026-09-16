rule PEiD_00559_Exe_Locker_1_0____IonIce_ {
  meta:
    description = "[Exe Locker 1.0 -> IonIce]"
    ep_only     = "true"

  strings:
    $a = { E8 00 00 00 00 60 8B 6C 24 20 81 ED 05 00 00 00 }

  condition:
    $a
}