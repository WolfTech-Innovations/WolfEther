# Use the official Golang image as a base image
FROM golang:latest AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy the Go source code into the container
COPY . .

# Build the Go application
RUN go build -o main .

# Create a new stage for the final image
FROM alpine:latest

# Copy the binary from the builder stage
COPY --from=builder /app/main /app/main

# Set the entry point for the container
ENTRYPOINT ["/app/main"]
