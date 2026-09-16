rule TTP_XOR_WriteProcessMemory_bb87 {
  strings:
    $key_bb87 = { ec f5 [2] de d7 [2] d8 e2 [2] f6 e2 [2] c9 fe }

  condition:
    any of them
}