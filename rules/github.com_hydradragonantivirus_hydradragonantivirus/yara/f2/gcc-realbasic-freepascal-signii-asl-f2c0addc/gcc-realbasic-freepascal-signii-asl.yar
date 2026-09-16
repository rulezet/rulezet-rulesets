import "pe"
rule _GCC_RealBasic_FreePascal_signII_ASL_ {
  meta:
    description = "GCC RealBasic/ FreePascal signII *ASL"

  strings:
    $0 = { 55 89 E5 83 EC 18 83 3D 00 ?? ?? 00 00 74 01 CC D9 7D FE 0F B7 45 FE 25 C0 F0 FF FF 66 89 45 FE 0F B7 45 FE 0D 3F 03 00 00 66 89 45 FE D9 6D FE 83 C4 }

  condition:
    $0 at pe.entry_point
}