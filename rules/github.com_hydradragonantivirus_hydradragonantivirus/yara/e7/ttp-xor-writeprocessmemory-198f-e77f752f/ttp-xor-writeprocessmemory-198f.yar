rule TTP_XOR_WriteProcessMemory_198f {
  strings:
    $key_198f = { 4e fd [2] 7c df [2] 7a ea [2] 54 ea [2] 6b f6 }

  condition:
    any of them
}