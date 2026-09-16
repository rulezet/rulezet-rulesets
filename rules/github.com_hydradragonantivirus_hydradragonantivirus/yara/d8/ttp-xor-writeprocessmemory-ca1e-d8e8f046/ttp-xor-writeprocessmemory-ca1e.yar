rule TTP_XOR_WriteProcessMemory_ca1e {
  strings:
    $key_ca1e = { 9d 6c [2] af 4e [2] a9 7b [2] 87 7b [2] b8 67 }

  condition:
    any of them
}