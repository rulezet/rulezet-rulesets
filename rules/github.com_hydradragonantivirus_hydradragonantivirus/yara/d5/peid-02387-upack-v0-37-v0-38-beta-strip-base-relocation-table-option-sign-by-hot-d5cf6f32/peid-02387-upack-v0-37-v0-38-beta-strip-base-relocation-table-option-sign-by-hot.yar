rule PEiD_02387_Upack_v0_37___v0_38_Beta__Strip_base_relocation_table_Option_____Sign_by_hot_UNP_ {
  meta:
    description = "[Upack v0.37 ~ v0.38 Beta (Strip base relocation table Option) -> Sign by hot_UNP]"
    ep_only     = "false"

  strings:
    $a = { 53 18 33 C0 55 40 51 D3 E0 8B EA 91 FF 56 4C 33 }

  condition:
    $a
}