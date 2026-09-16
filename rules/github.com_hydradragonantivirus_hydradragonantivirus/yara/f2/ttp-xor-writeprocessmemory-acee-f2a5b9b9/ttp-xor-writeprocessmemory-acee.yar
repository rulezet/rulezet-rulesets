rule TTP_XOR_WriteProcessMemory_acee {
  strings:
    $key_acee = { fb 9c [2] c9 be [2] cf 8b [2] e1 8b [2] de 97 }

  condition:
    any of them
}