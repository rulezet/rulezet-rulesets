rule TTP_XOR_WriteProcessMemory_8335 {
  strings:
    $key_8335 = { d4 47 [2] e6 65 [2] e0 50 [2] ce 50 [2] f1 4c }

  condition:
    any of them
}