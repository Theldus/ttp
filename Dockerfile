FROM scratch
COPY ttp /ttp
EXPOSE 7171/tcp
CMD ["/ttp"]
