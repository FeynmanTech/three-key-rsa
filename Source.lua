
--# Main
-- RSA

-- Use this function to perform your initial setup
function test()
    cl=Client(12345)
    sv=Server(234,567)
    cl:keygen(sv)
    print(cl.key, sv.key)
    
    msg=triple({"CRYPT","RADIO","MILES"})
    msg:make("triple key rsa encryptiom", 5, 1, 3, "ACDBFE", cl.key)
    print(msg.t)
    --pasteboard.copy(msg.t)
    --pasteboard.copy(cl.key)
end

--# Ops
function prime(n)
    for i = 2, n^(1/2) do
        if (n % i) == 0 then
            return false
        end
        return true
    end
end

function factors( n ) 
    local f = {}
    for i = 1, n/2 do
        if n % i == 0 then 
            f[#f+1] = i
        end
    end
    f[#f+1] = n
    return f
end

function b26(IN)
    if IN==0 then return "A" end
    local B,K,OUT,I,D=26,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","",0
    while IN>0 do
        I=I+1
        IN,D=math.floor(IN/B),IN%B+1
        OUT=string.sub(K,D,D)..OUT
    end
    return OUT
end

function b10(str)
    local c="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    str=str:gsub("(.)", function(ch) return c:sub(c:find(ch)-10, c:find(ch)-10) end)
    return tonumber(str, 26)
end

function trim(s)
    if s then
        return (s:gsub("^%s*(.-)%s*$", "%1"))
    end
end
--# Client
Client = class()

function Client:init(priv)
    -- you can accept and set parameters here
    self.priv = priv
end

function Client:keygen(server)
    local t=factors(self.priv)
    local m=0
    for i, v in ipairs(t) do
        if(prime(v)) then m=math.max(m,v) end
    end
    self.key = server:keygen(m)*m
    return self.key
end

--# Server
Server = class()

function Server:init(priv, pub)
    -- you can accept and set parameters here
    self.priv = priv
    self.pub = pub
end

function Server:keygen(key)
    local t=factors(self.priv)
    local m=0
    for i, v in ipairs(t) do
        if(prime(v)) then m=math.max(m,v) end
    end
    self.key=key*m*self.pub
    return self.pub*m
end
--# Random
Random = class()

function Random:init(seed)
    -- you can accept and set parameters here
    self.seed = seed
end

function Random:next(min, max)
    self.seed=self.seed+1
    if min==max then return min end
    return ((self.seed % 50000) ^ (2.7128 / 1) % (max-min))+min
end

--# Triple
triple = class()

function triple:init(keys)
    -- you can accept and set parameters here
    self.keys = keys
end

function triple:make(str, blocks, insertionkey, shufflekey, shuffledata, seed)
    local rand=Random(seed)
    str=trim(str)
    str=str:gsub("%s","")
    local len=b26(#str-1)
    self.t=b26(#len-1)..len
    
    local bl=b26(blocks-1)
    self.t=self.t..b26(#bl-1)..bl
    
    self.t=self.t..b26(#self.keys[insertionkey]-1)..b26(insertionkey-1)
    
    self.t=self.t..b26(#self.keys[shufflekey]-1)..b26(shufflekey-1)
    
    self.t=self.t..b26(#shuffledata-1)..shuffledata
    
    local bsize=#str/blocks
    local st={}
    local sh={}
    local cc=100
    local tc=0
    local cp
    for _n=1,bsize do
        for n=1,bsize do
            if self.keys[shufflekey]:sub(n,n):byte()<cc and self.keys[shufflekey]:sub(n,n):byte()>tc then
                --table.insert(sh, n)
                cc=self.keys[shufflekey]:sub(n,n):byte()
                cp=n
            end
        end
        tc=cc
        table.insert(sh,cp)
        cc=100
    end
    for n=1,#self.keys[insertionkey] do
        local m
        for p=1,#str do
            if str:sub(p,p):upper()==self.keys[insertionkey]:sub(n,n):upper() then
                local pos=math.tointeger(math.floor(rand:next(0,p-1)))
                str=str:sub(0,pos)..self.keys[insertionkey]:sub(n,n)..str:sub(pos+1,-1)
                break
            end
        end
    end
    local rb={}
    for n=1,#str,blocks do
        table.insert(rb, str:sub(n,n+4))
    end
    local sb={}
    for n=1, #shuffledata do
        table.insert(sb, rb[b10(shuffledata:sub(n,n))+1])
    end
    local order={}
    local cm=256
    local mm=""
    local cmm=""
    for n=1,blocks do
        local cp
        cm=256
        for cn=1,#self.keys[shufflekey] do
            if self.keys[shufflekey]:sub(cn,cn):byte()<cm and not(mm:find(self.keys[shufflekey]:sub(cn,cn))) then
                cm=self.keys[shufflekey]:sub(cn,cn):byte()
                --print(cm)
                cp=cn
                cmm=self.keys[shufflekey]:sub(cn,cn)
            end
        end
        mm=mm..cmm
        table.insert(order, cp)
        --print(cp)
        --mm=cm
        --cm=256
        --print(mm)
    end
    --print(table.concat(order,""))
    local scrambled=""
    for i, v in ipairs(sb) do
        for n=1,5 do
            scrambled=scrambled..v:sub(order[n],order[n])
        end
    end
    self.t=self.t..scrambled
    self.t=self.t:upper()
end

function triple:unmake(str, blocks, insertionkey, shufflekey, shuffledata, seed)
    local rand=Random(seed)
    str=trim(str)
    str=str:gsub("%s","")
    local len=b26(#str-1)
    self.t=b26(#len-1)..len
    
    local bl=b26(blocks-1)
    self.t=self.t..b26(#bl-1)..bl
    
    self.t=self.t..b26(#self.keys[insertionkey]-1)..b26(insertionkey-1)
    
    self.t=self.t..b26(#self.keys[shufflekey]-1)..b26(shufflekey-1)
    
    self.t=self.t..b26(#shuffledata-1)..shuffledata
    
    local bsize=#str/blocks
    local st={}
    local sh={}
    local cc=100
    local tc=0
    local cp
    for _n=1,bsize do
        for n=1,bsize do
            if self.keys[shufflekey]:sub(n,n):byte()<cc and self.keys[shufflekey]:sub(n,n):byte()>tc then
                --table.insert(sh, n)
                cc=self.keys[shufflekey]:sub(n,n):byte()
                cp=n
            end
        end
        tc=cc
        table.insert(sh,cp)
        cc=100
    end
    for n=1,#self.keys[insertionkey] do
        local m
        for p=1,#str do
            if str:sub(p,p):upper()==self.keys[insertionkey]:sub(n,n):upper() then
                local pos=math.tointeger(math.floor(rand:next(0,p-1)))
                str=str:sub(0,pos)..self.keys[insertionkey]:sub(n,n)..str:sub(pos+1,-1)
                break
            end
        end
    end
    local rb={}
    for n=1,#str,blocks do
        table.insert(rb, str:sub(n,n+4))
    end
    local sb={}
    for n=1, #shuffledata do
        table.insert(sb, rb[b10(shuffledata:sub(n,n))+1])
    end
    local order={}
    local cm=256
    local mm=""
    local cmm=""
    for n=1,blocks do
        local cp
        cm=256
        for cn=1,#self.keys[shufflekey] do
            if self.keys[shufflekey]:sub(cn,cn):byte()<cm and not(mm:find(self.keys[shufflekey]:sub(cn,cn))) then
                cm=self.keys[shufflekey]:sub(cn,cn):byte()
                --print(cm)
                cp=cn
                cmm=self.keys[shufflekey]:sub(cn,cn)
            end
        end
        mm=mm..cmm
        table.insert(order, cp)
        --print(cp)
        --mm=cm
        --cm=256
        --print(mm)
    end
    --print(table.concat(order,""))
    local scrambled=""
    for i, v in ipairs(sb) do
        for n=1,5 do
            scrambled=scrambled..v:sub(order[n],order[n])
        end
    end
    self.t=self.t..scrambled
    self.t=self.t:upper()
end

function triple:touched(touch)
    -- Codea does not automatically call this method
end

--# Comments
--[[
Message:    "triple key rsa encryption"
Encrypted:  "AVAEEAECFACDBFETTRYPYKEERNAESCLIPRCMOTYPRI"
Keys:       "CRYPT", "RADIO", "MILES"
Seed:        818954955
--]]
