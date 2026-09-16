rule TTP_XOR_WriteProcessMemory_898e {
  strings:
    $key_898e = { de fc [2] ec de [2] ea eb [2] c4 eb [2] fb f7 }

  condition:
    any of them
}