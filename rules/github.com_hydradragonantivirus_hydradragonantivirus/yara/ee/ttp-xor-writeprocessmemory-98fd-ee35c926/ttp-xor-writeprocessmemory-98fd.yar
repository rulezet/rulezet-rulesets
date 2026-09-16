rule TTP_XOR_WriteProcessMemory_98fd {
  strings:
    $key_98fd = { cf 8f [2] fd ad [2] fb 98 [2] d5 98 [2] ea 84 }

  condition:
    any of them
}