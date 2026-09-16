rule TTP_XOR_WriteProcessMemory_d03b {
  strings:
    $key_d03b = { 87 49 [2] b5 6b [2] b3 5e [2] 9d 5e [2] a2 42 }

  condition:
    any of them
}