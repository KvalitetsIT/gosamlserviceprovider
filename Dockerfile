FROM kit/git as sshsecret

FROM golang:1.13.4 as builder
ENV GO111MODULE=on

# add credentials on build and make sure github.xom is accepted
RUN mkdir /root/.ssh/
COPY --from=sshsecret /id_rsa /root/.ssh/id_rsa
RUN chmod 700 /root/.ssh/id_rsa
RUN touch /root/.ssh/known_hosts
RUN ssh-keyscan github.com >> /root/.ssh/known_hosts
ADD gitconfig /root/.gitconfig

# Prepare for custom caddy build
RUN mkdir /gosamlserviceprovider
WORKDIR /gosamlserviceprovider
RUN go mod init gosamlserviceprovider

RUN echo "replace github.com/russellhaering/goxmldsig => github.com/evtr/goxmldsig latest" >> go.mod

ENV GOPRIVATE="github.com/KvalitetsIT/gosecurityprotocol"
# Using Docker's layers to cache the following libraries
RUN echo "kuk11 d225"
#RUN go get github.com/google/uuid
RUN go get github.com/KvalitetsIT/gosecurityprotocol
RUN go get github.com/russellhaering/gosaml2
RUN go get gotest.tools/assert


RUN apt-get update
RUN apt-get -y install wget --fix-missing
RUN apt-get -y install xvfb --fix-missing # chrome will use this to run headlessly
RUN apt-get -y install unzip --fix-missing

# install dbus - chromedriver needs this to talk to google-chrome
RUN apt-get -y install dbus --fix-missing
RUN apt-get -y install dbus-x11 --fix-missing
#RUN ln -s /bin/dbus-daemon /usr/bin/dbus-daemon     # /etc/init.d/dbus has the wrong location
#RUN ln -s /bin/dbus-uuidgen /usr/bin/dbus-uuidgen   # /etc/init.d/dbus has the wrong location

# install chrome
RUN wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add -
RUN sh -c 'echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google-chrome.list'
RUN apt-get update
RUN apt-get -y install google-chrome-stable


RUN wget -N http://chromedriver.storage.googleapis.com/77.0.3865.40/chromedriver_linux64.zip
RUN unzip chromedriver_linux64.zip
RUN chmod +x chromedriver
RUN mv -f chromedriver /usr/local/bin/chromedriver


COPY . /gosamlserviceprovider/
RUN go test gosamlserviceprovider
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /go/bin/gosamlserviceprovider .
