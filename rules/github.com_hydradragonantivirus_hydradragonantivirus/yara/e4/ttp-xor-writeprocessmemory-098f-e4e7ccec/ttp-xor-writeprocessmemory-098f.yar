rule TTP_XOR_WriteProcessMemory_098f {
  strings:
    $key_098f = { 5e fd [2] 6c df [2] 6a ea [2] 44 ea [2] 7b f6 }

  condition:
    any of them
}