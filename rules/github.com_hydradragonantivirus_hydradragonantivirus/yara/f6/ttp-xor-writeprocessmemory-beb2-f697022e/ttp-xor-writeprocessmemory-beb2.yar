rule TTP_XOR_WriteProcessMemory_beb2 {
  strings:
    $key_beb2 = { e9 c0 [2] db e2 [2] dd d7 [2] f3 d7 [2] cc cb }

  condition:
    any of them
}