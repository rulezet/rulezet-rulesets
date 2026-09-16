rule TTP_XOR_WriteProcessMemory_d08e {
  strings:
    $key_d08e = { 87 fc [2] b5 de [2] b3 eb [2] 9d eb [2] a2 f7 }

  condition:
    any of them
}