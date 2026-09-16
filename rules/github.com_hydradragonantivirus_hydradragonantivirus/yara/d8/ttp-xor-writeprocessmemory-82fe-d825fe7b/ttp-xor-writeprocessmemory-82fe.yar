rule TTP_XOR_WriteProcessMemory_82fe {
  strings:
    $key_82fe = { d5 8c [2] e7 ae [2] e1 9b [2] cf 9b [2] f0 87 }

  condition:
    any of them
}