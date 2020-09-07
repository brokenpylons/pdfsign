package com.brokenpylons.pdfsign;

class Config {
    final public String name;
    final public String reason;
    final public String location;
    final int x;
    final int y;

    public Config(String name, String reason, String location, int x, int y) {
        this.name = name;
        this.reason = reason;
        this.location = location;
        this.x = x;
        this.y = y;
    }
}
