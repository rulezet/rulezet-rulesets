rule TTP_XOR_WriteProcessMemory_c9bd {
  strings:
    $key_c9bd = { 9e cf [2] ac ed [2] aa d8 [2] 84 d8 [2] bb c4 }

  condition:
    any of them
}