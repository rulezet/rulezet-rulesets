rule TTP_XOR_WriteProcessMemory_da8e {
  strings:
    $key_da8e = { 8d fc [2] bf de [2] b9 eb [2] 97 eb [2] a8 f7 }

  condition:
    any of them
}