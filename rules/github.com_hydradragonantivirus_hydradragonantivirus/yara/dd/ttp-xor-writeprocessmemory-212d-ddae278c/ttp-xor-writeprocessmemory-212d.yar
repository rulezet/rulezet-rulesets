rule TTP_XOR_WriteProcessMemory_212d {
  strings:
    $key_212d = { 76 5f [2] 44 7d [2] 42 48 [2] 6c 48 [2] 53 54 }

  condition:
    any of them
}