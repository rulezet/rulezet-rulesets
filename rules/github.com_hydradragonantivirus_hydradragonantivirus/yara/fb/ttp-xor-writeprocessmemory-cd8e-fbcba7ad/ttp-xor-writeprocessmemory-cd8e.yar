rule TTP_XOR_WriteProcessMemory_cd8e {
  strings:
    $key_cd8e = { 9a fc [2] a8 de [2] ae eb [2] 80 eb [2] bf f7 }

  condition:
    any of them
}