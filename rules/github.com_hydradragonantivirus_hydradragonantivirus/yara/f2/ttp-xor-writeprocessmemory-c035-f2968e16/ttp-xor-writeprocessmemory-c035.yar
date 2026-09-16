rule TTP_XOR_WriteProcessMemory_c035 {
  strings:
    $key_c035 = { 97 47 [2] a5 65 [2] a3 50 [2] 8d 50 [2] b2 4c }

  condition:
    any of them
}