rule PEiD_01019_Mew_10_exe_coder_1_0____Northfox__HCC__ {
  meta:
    description = "[Mew 10 exe-coder 1.0 -> Northfox [HCC]]"
    ep_only     = "true"

  strings:
    $a = { 33 C0 E9 ?? ?? FF FF 6A ?? ?? ?? ?? ?? 70 }

  condition:
    $a
}