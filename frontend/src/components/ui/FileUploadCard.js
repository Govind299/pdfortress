import React, { useState, useRef, forwardRef } from "react";
import { UploadCloud, X, CheckCircle2, Trash2 } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

function cn(...classes) {
  return classes.filter(Boolean).join(" ");
}

export const FileUploadCard = forwardRef(function FileUploadCard(
  {
    className,
    files = [],
    onFilesChange,
    onFileRemove,
    onClose,
    onStartScan,
    isLoading = false,
    password = "",
    onPasswordChange,
    ...props
  },
  ref
) {
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef(null);

  const handleDragEnter = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    const droppedFiles = Array.from(e.dataTransfer.files || []);
    if (droppedFiles.length > 0) {
      onFilesChange(droppedFiles);
    }
  };

  const handleFileSelect = (e) => {
    const selectedFiles = Array.from(e.target.files || []);
    if (selectedFiles.length > 0) {
      onFilesChange(selectedFiles);
    }
  };

  const triggerFileSelect = () => {
    if (fileInputRef.current) {
      fileInputRef.current.click();
    }
  };

  const formatFileSize = (bytes) => {
    if (!bytes || bytes === 0) return "0 KB";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  };

  const cardVariants = {
    hidden: { opacity: 0, y: 20 },
    visible: { opacity: 1, y: 0 }
  };

  const fileItemVariants = {
    hidden: { opacity: 0, x: -20 },
    visible: { opacity: 1, x: 0 }
  };

  return (
    <motion.div
      ref={ref}
      variants={cardVariants}
      initial="hidden"
      animate="visible"
      transition={{ duration: 0.3 }}
      className={cn(
        "w-full max-w-xl bg-white rounded-xl border border-gray-200 shadow-sm text-left mx-auto",
        className
      )}
      style={{
        backgroundColor: "#ffffff",
        border: "1px solid #ebebeb",
        borderRadius: "12px",
        padding: "24px",
        maxWidth: "640px",
        width: "100%",
        boxShadow: "0 1px 3px rgba(0,0,0,0.05)"
      }}
      {...props}
    >
      {/* Header Bar */}
      <div
        style={{
          display: "flex",
          justify: "space-between",
          alignItems: "center",
          marginBottom: "16px",
          paddingBottom: "12px",
          borderBottom: "1px solid #f0f0f0"
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <div
            style={{
              width: "8px",
              height: "8px",
              borderRadius: "50%",
              backgroundColor: "#171717"
            }}
          />
          <span style={{ fontSize: "14px", fontWeight: "600", color: "#171717" }}>
            PDF Document Scanner
          </span>
        </div>

        {onClose && (
          <button
            type="button"
            onClick={onClose}
            style={{
              background: "none",
              border: "none",
              cursor: "pointer",
              color: "#8f8f8f",
              padding: "4px"
            }}
          >
            <X style={{ width: "16px", height: "16px" }} />
          </button>
        )}
      </div>

      {/* Hidden File Input */}
      <input
        ref={fileInputRef}
        type="file"
        multiple
        accept=".pdf"
        onChange={handleFileSelect}
        style={{ display: "none" }}
      />

      {/* Dropzone Container */}
      <div
        onDragEnter={handleDragEnter}
        onDragLeave={handleDragLeave}
        onDragOver={handleDragOver}
        onDrop={handleDrop}
        onClick={triggerFileSelect}
        style={{
          border: isDragging ? "2px dashed #171717" : "1px dashed #e0e0e0",
          backgroundColor: isDragging ? "#fafafa" : "#fcfcfc",
          borderRadius: "8px",
          padding: "32px 16px",
          textAlign: "center",
          cursor: "pointer",
          transition: "all 0.2s ease"
        }}
      >
        <div
          style={{
            width: "40px",
            height: "40px",
            borderRadius: "50%",
            backgroundColor: "#f5f5f5",
            display: "flex",
            alignItems: "center",
            justify: "center",
            margin: "0 auto 12px auto"
          }}
        >
          <UploadCloud style={{ width: "20px", height: "20px", color: "#171717" }} />
        </div>
        <p style={{ fontSize: "14px", fontWeight: "500", color: "#171717", margin: 0 }}>
          Click to upload or drag and drop PDF files
        </p>
        <p style={{ fontSize: "12px", color: "#8f8f8f", marginTop: "4px", margin: 0 }}>
          Only PDF format supported (Max size 100 MB)
        </p>
      </div>

      {/* Uploaded File List */}
      {files.length > 0 && (
        <div style={{ marginTop: "16px" }}>
          <div
            style={{
              fontSize: "12px",
              fontWeight: "600",
              color: "#8f8f8f",
              textTransform: "uppercase",
              letterSpacing: "0.5px",
              marginBottom: "8px"
            }}
          >
            Uploaded Files ({files.length})
          </div>

          <ul style={{ listStyle: "none", padding: 0, margin: 0 }}>
            <AnimatePresence>
              {files.map((fileItem) => (
                <motion.li
                  key={fileItem.id}
                  variants={fileItemVariants}
                  initial="hidden"
                  animate="visible"
                  exit={{ opacity: 0, height: 0, marginTop: 0 }}
                  transition={{ duration: 0.2 }}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justify: "space-between",
                    padding: "10px 12px",
                    backgroundColor: "#fafafa",
                    borderRadius: "6px",
                    border: "1px solid #f0f0f0",
                    marginBottom: "8px"
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: "10px", minWidth: 0 }}>
                    <CheckCircle2 style={{ width: "16px", height: "16px", color: "#10b981", flexShrink: 0 }} />
                    <div style={{ minWidth: 0 }}>
                      <p
                        style={{
                          fontSize: "13px",
                          fontWeight: "500",
                          color: "#171717",
                          margin: 0,
                          whiteSpace: "nowrap",
                          overflow: "hidden",
                          textOverflow: "ellipsis"
                        }}
                      >
                        {fileItem.file.name}
                      </p>
                      <p style={{ fontSize: "11px", color: "#8f8f8f", margin: 0 }}>
                        {formatFileSize(fileItem.file.size)}
                      </p>
                    </div>
                  </div>

                  <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        onFileRemove(fileItem.id);
                      }}
                      style={{
                        background: "none",
                        border: "none",
                        cursor: "pointer",
                        padding: "6px",
                        borderRadius: "50%",
                        color: "#8f8f8f"
                      }}
                    >
                      {fileItem.status === 'completed' ? (
                        <Trash2 style={{ width: "16px", height: "16px" }} />
                      ) : (
                        <X style={{ width: "16px", height: "16px" }} />
                      )}
                    </button>
                  </div>
                </motion.li>
              ))}
            </AnimatePresence>
          </ul>

          {/* Password Input & Scan Action Button */}
          <div style={{ marginTop: "16px", display: "flex", gap: "12px", alignItems: "center", justifyContent: "space-between" }}>
            <input
              type="password"
              placeholder="🔒 Password (Optional for encrypted PDFs)"
              value={password}
              onChange={(e) => onPasswordChange && onPasswordChange(e.target.value)}
              style={{
                flex: 1,
                padding: "8px 14px",
                fontSize: "13px",
                borderRadius: "6px",
                border: "1px solid #e0e0e0",
                backgroundColor: "#fcfcfc",
                color: "#171717",
                fontFamily: "monospace",
                outline: "none"
              }}
            />
            <button
              type="button"
              onClick={onStartScan}
              disabled={isLoading}
              style={{
                backgroundColor: "#171717",
                color: "#ffffff",
                borderRadius: "100px",
                padding: "10px 24px",
                fontSize: "14px",
                fontWeight: "500",
                border: "none",
                cursor: "pointer",
                whiteSpace: "nowrap",
                opacity: isLoading ? 0.6 : 1
              }}
            >
              {isLoading ? "Running Security Scan..." : "Analyze Document"}
            </button>
          </div>
        </div>
      )}
    </motion.div>
  );
});

export default FileUploadCard;
