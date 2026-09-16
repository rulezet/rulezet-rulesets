import "pe"
rule Mew_10_exe_coder_1_0_____Northfox_rule__HCC_ {
  strings:
    $a0 = { 33 C0 E9 ?? ?? FF FF 6A ?? ?? ?? ?? ?? 70 }

  condition:
    $a0 at pe.entry_point
}