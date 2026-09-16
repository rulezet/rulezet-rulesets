rule TTP_XOR_WriteProcessMemory_d78e {
  strings:
    $key_d78e = { 80 fc [2] b2 de [2] b4 eb [2] 9a eb [2] a5 f7 }

  condition:
    any of them
}