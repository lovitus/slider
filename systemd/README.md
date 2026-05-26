## Service

### Install

#### 1. copy binary file

```bash
cp slider /usr/bin/
```

#### 2. add service file

```bash
# copy service file to systemd
cp systemd/slider@.service /etc/systemd/system/
```

#### 3. add config file: ***slider***.conf

```bash
# copy config file to /etc/slider/
mkdir /etc/slider/
cp ./config/slider.conf.example /etc/slider/slider.conf
```

#### 4. enable and start service: slider@***slider***

```bash
# enable and start service
systemctl enable slider@slider
systemctl start slider@slider
```

See [slider@.service](slider%40.service)
