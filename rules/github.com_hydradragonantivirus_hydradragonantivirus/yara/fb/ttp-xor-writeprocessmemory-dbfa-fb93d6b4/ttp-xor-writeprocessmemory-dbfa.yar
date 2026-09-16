rule TTP_XOR_WriteProcessMemory_dbfa {
  strings:
    $key_dbfa = { 8c 88 [2] be aa [2] b8 9f [2] 96 9f [2] a9 83 }

  condition:
    any of them
}