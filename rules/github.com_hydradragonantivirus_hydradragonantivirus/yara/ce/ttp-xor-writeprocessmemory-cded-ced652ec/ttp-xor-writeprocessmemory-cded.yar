rule TTP_XOR_WriteProcessMemory_cded {
  strings:
    $key_cded = { 9a 9f [2] a8 bd [2] ae 88 [2] 80 88 [2] bf 94 }

  condition:
    any of them
}