FROM golang

# Use the official Golang image as a base image
# Set the working directory inside the container
WORKDIR /

# Copy the Go source code into the container
COPY . .

# Build the Go application
RUN go build -o /main cmd/node/main.go

# Set the entry point for the container
ENTRYPOINT ["/main"]

EXPOSE 9050
EXPOSE 8546
EXPOSE 8545