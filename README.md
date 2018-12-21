# happyJWT
### Simple JWT tool for your Python programming

#### Happiness comes from simpleness.



## Usage

### Install

```python
pip install happyJWT
```



### Create

**Get happy**

```python
from happyJWT.happy import JWT
```

**Simplest Happiness**

```python
jwt = JWT.new('q').value
```

where 'q' is a key used in Hash Security Algorithms that makes our JWT a little bit salty,  and could be any short string.

The simplest happiness provides default value **3000** as the `exp` and **HS256** as the `alg` for our JWT.

**More Happiness**

```python
jwt = JWT.new('q', 7200, 'HS512').value
```

which uses HS512 to generate the signature of our JWT and allows it to be alive for 2 hours.

Also, you we can get each component of our JWT by codes like:

```python
jwt = JWT.new('q', 7200, 'HS512')
header = jwt.header
payload = jwt.payload
signature = jwt.signature
```

**Bigger Happiness**

We can initualize more arguments in `new()`

```python
jwt = JWT.new('q', 7200, 'HS512',
              author='Leonard',
              subject='Happy',
              data={
                  'uername': 'xxxx',
                  'uid': 222,
              }).value
```

where arguments **data** is some private data which could be necessary in our web project and the **author** our name, **subject** what out project is about.



### Verify

```python
JWT.verify('header.payload.signature', 'q')
```

The first argument is the JWT that needs verifying, and 'q' is the salt same as that above.



### Get the private data in JWT

```python
JWT.get_private_data('xxx')
```

'xxx' can be a full formatted JWT or just the payload of it.





### Some Static Methods

`happyJWT` provides two static methods about base64 translations.

```python
from happyJWT.happy import b64enc, b64dec

b = b64enc('a')
s = b64dec('Q==')
```



And some Hash Security Algorithm calculations that are often used in projects.

```python
from happyJWT.happy import Hash

h = Hash.sha256('aaa', 'q')
```

where 'q' is still our salt.

There're 5 other algorithms for us to use:

`sha1` `sha224` `sha384` `sha512` `md5`



