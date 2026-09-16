rule TTP_XOR_WriteProcessMemory_9ead {
  strings:
    $key_9ead = { c9 df [2] fb fd [2] fd c8 [2] d3 c8 [2] ec d4 }

  condition:
    any of them
}