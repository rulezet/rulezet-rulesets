rule TTP_XOR_WriteProcessMemory_9899 {
  strings:
    $key_9899 = { cf eb [2] fd c9 [2] fb fc [2] d5 fc [2] ea e0 }

  condition:
    any of them
}