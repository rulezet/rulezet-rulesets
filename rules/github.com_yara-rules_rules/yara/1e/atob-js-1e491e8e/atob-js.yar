rule atob_js {
    strings: $ = "this['eval'](this['atob']('"
    condition: any of them
}