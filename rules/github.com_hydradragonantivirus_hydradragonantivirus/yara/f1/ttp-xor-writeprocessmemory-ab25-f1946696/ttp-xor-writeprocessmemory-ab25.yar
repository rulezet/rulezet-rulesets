rule TTP_XOR_WriteProcessMemory_ab25 {
  strings:
    $key_ab25 = { fc 57 [2] ce 75 [2] c8 40 [2] e6 40 [2] d9 5c }

  condition:
    any of them
}