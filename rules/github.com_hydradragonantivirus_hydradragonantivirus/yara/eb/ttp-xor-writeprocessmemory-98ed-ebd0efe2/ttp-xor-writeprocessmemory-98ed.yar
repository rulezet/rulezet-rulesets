rule TTP_XOR_WriteProcessMemory_98ed {
  strings:
    $key_98ed = { cf 9f [2] fd bd [2] fb 88 [2] d5 88 [2] ea 94 }

  condition:
    any of them
}