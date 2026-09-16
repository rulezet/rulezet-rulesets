rule TTP_XOR_WriteProcessMemory_938e {
  strings:
    $key_938e = { c4 fc [2] f6 de [2] f0 eb [2] de eb [2] e1 f7 }

  condition:
    any of them
}