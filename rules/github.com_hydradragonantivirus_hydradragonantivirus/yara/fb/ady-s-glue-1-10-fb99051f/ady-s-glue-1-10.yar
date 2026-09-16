import "pe"
rule Ady_s_Glue_1_10 {
  strings:
    $a0 = { 2E ?? ?? ?? ?? 0E 1F BF ?? ?? 33 DB 33 C0 AC }

  condition:
    $a0 at pe.entry_point
}