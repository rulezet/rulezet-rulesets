rule TTP_XOR_WriteProcessMemory_ade4 {
  strings:
    $key_ade4 = { fa 96 [2] c8 b4 [2] ce 81 [2] e0 81 [2] df 9d }

  condition:
    any of them
}