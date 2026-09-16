rule TTP_XOR_WriteProcessMemory_ade5 {
  strings:
    $key_ade5 = { fa 97 [2] c8 b5 [2] ce 80 [2] e0 80 [2] df 9c }

  condition:
    any of them
}