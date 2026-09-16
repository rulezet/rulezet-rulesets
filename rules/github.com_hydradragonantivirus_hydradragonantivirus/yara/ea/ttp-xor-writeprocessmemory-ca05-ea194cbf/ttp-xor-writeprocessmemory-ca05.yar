rule TTP_XOR_WriteProcessMemory_ca05 {
  strings:
    $key_ca05 = { 9d 77 [2] af 55 [2] a9 60 [2] 87 60 [2] b8 7c }

  condition:
    any of them
}