rule TTP_XOR_QUAD_CurrentVersionRun_0808 {
  strings:
    $key_0808 = { 5b 67 [2] 7f 69 [2] 54 45 [2] 7a 67 [2] 6e 7c [2] 61 66 [2] 7f 7b [2] 7d 7a [2] 66 7c [2] 7a 7b [2] 66 54 }

  condition:
    any of them
}