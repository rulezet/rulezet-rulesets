rule TTP_XOR_QUAD_CurrentVersionRun_b992 {
  strings:
    $key_b992 = { ea fd [2] ce f3 [2] e5 df [2] cb fd [2] df e6 [2] d0 fc [2] ce e1 [2] cc e0 [2] d7 e6 [2] cb e1 [2] d7 ce }

  condition:
    any of them
}