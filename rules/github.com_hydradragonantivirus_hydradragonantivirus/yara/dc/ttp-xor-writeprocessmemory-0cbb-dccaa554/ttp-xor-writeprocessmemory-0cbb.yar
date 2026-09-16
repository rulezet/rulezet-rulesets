rule TTP_XOR_WriteProcessMemory_0cbb {
  strings:
    $key_0cbb = { 5b c9 [2] 69 eb [2] 6f de [2] 41 de [2] 7e c2 }

  condition:
    any of them
}