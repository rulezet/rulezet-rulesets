rule TTP_XOR_WriteProcessMemory_f50c {
  strings:
    $key_f50c = { a2 7e [2] 90 5c [2] 96 69 [2] b8 69 [2] 87 75 }

  condition:
    any of them
}