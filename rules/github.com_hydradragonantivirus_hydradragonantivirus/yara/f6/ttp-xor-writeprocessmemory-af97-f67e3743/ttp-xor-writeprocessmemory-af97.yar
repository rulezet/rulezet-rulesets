rule TTP_XOR_WriteProcessMemory_af97 {
  strings:
    $key_af97 = { f8 e5 [2] ca c7 [2] cc f2 [2] e2 f2 [2] dd ee }

  condition:
    any of them
}