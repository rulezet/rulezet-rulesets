rule TTP_XOR_WriteProcessMemory_9f8e {
  strings:
    $key_9f8e = { c8 fc [2] fa de [2] fc eb [2] d2 eb [2] ed f7 }

  condition:
    any of them
}