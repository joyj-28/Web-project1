
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

dotenv.config();

const app = express();

app.use(cors({ origin: "http://localhost:5173" }));
app.use(express.json({ limit: "20kb" }));
app.use(express.json());
// ---------- DATABASE MODELS ----------

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true, maxlength: 80 },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    passwordHash: { type: String, required: true },
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);

const groupSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    subject: { type: String, required: true, trim: true },
    members: { type: Number, default: 1, min: 1 },
    ownerId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  },
  { timestamps: true }
);

const Group = mongoose.model("Group", groupSchema);

const groupMemberSchema = new mongoose.Schema(
  {
    groupId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Group",
      required: true,
    },
    name: { type: String, required: true, trim: true, maxlength: 80 },
    email: { type: String, required: true, lowercase: true, trim: true },
  },
  { timestamps: true }
);

groupMemberSchema.index({ groupId: 1, email: 1 }, { unique: true });

const GroupMember = mongoose.model("GroupMember", groupMemberSchema);

const sessionSchema = new mongoose.Schema(
  {
    title: { type: String, required: true, trim: true, maxlength: 120 },
    subject: { type: String, required: true, trim: true, maxlength: 100 },
    groupId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Group",
      required: true,
    },
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    startAt: { type: Date, required: true },
    location: { type: String, trim: true, maxlength: 200, default: "" },
    meetingLink: { type: String, trim: true, maxlength: 500, default: "" },
  },
  { timestamps: true }
);

const StudySession = mongoose.model("StudySession", sessionSchema);

// ---------- AUTHENTICATION ----------

function createToken(user) {
  return jwt.sign(
    { userId: user._id.toString() },
    process.env.JWT_SECRET,
    { expiresIn: "2h" }
  );
}

function publicUser(user) {
  return {
    id: user._id,
    name: user.name,
    email: user.email,
  };
}

function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const [scheme, token] = header.split(" ");

  if (scheme !== "Bearer" || !token) {
    return res.status(401).json({
      success: false,
      message: "Please log in to continue.",
    });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = payload.userId;
    next();
  } catch {
    return res.status(401).json({
      success: false,
      message: "Your login has expired. Please log in again.",
    });
  }
}

async function canManageGroup(group, userId) {
  // Groups created before login was added have no owner.
  // Any logged-in user can manage these legacy groups.
  return !group.ownerId || group.ownerId.toString() === userId;
}

// ---------- BASIC ROUTES ----------

app.get("/", (req, res) => {
  res.json({ message: "StudySpace backend is running!" });
});

// ---------- REGISTER ----------

app.post("/api/auth/register", async (req, res) => {
  try {
    const name = req.body.name?.trim();
    const email = req.body.email?.trim().toLowerCase();
    const password = req.body.password;

    if (!name || !email || typeof password !== "string") {
      return res.status(400).json({
        success: false,
        message: "Name, email, and password are required.",
      });
    }

    if (name.length > 80 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({
        success: false,
        message: "Please enter a valid name and email address.",
      });
    }

    if (password.length < 8 || password.length > 72) {
      return res.status(400).json({
        success: false,
        message: "Password must be between 8 and 72 characters.",
      });
    }

    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(409).json({
        success: false,
        message: "An account with that email already exists.",
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const user = await User.create({ name, email, passwordHash });

    res.status(201).json({
      success: true,
      data: { user: publicUser(user), token: createToken(user) },
    });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({
        success: false,
        message: "An account with that email already exists.",
      });
    }

    console.error("Registration error:", error.message);
    res.status(500).json({
      success: false,
      message: "Registration failed.",
    });
  }
});

// ---------- LOGIN ----------

app.post("/api/auth/login", async (req, res) => {
  try {
    const email = req.body.email?.trim().toLowerCase();
    const password = req.body.password;

    if (!email || typeof password !== "string") {
      return res.status(400).json({
        success: false,
        message: "Email and password are required.",
      });
    }

    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password.",
      });
    }

    res.json({
      success: true,
      data: { user: publicUser(user), token: createToken(user) },
    });
  } catch (error) {
    console.error("Login error:", error.message);
    res.status(500).json({
      success: false,
      message: "Login failed.",
    });
  }
});

// Get the currently logged-in student
app.get("/api/auth/me", requireAuth, async (req, res) => {
  const user = await User.findById(req.userId).select("name email");

  if (!user) {
    return res.status(401).json({
      success: false,
      message: "Account not found.",
    });
  }

  res.json({ success: true, data: publicUser(user) });
});

// ---------- STUDY GROUPS ----------

// List groups (kept public so the existing dashboard can still load)
app.get("/api/groups", async (req, res) => {
  try {
    const groups = await Group.find().sort({ createdAt: -1 });
    res.json({ success: true, data: groups });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Could not load study groups.",
    });
  }
});

// Create a group (login required)
app.post("/api/groups", requireAuth, async (req, res) => {
  try {
    const name = req.body.name?.trim();
    const subject = req.body.subject?.trim();

    if (!name || !subject) {
      return res.status(400).json({
        success: false,
        message: "Group name and subject are required.",
      });
    }

    const group = await Group.create({
      name,
      subject,
      members: 1,
      ownerId: req.userId,
    });

    res.status(201).json({ success: true, data: group });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Could not create the group.",
    });
  }
});

// Edit a group (login required)
app.patch("/api/groups/:id", requireAuth, async (req, res) => {
  try {
    const group = await Group.findById(req.params.id);

    if (!group) {
      return res.status(404).json({
        success: false,
        message: "Study group not found.",
      });
    }

    if (!(await canManageGroup(group, req.userId))) {
      return res.status(403).json({
        success: false,
        message: "You cannot edit this group.",
      });
    }

    if (req.body.name !== undefined) {
      if (typeof req.body.name !== "string" || !req.body.name.trim()) {
        return res.status(400).json({
          success: false,
          message: "Group name cannot be empty.",
        });
      }
      group.name = req.body.name.trim();
    }

    if (req.body.subject !== undefined) {
      if (
        typeof req.body.subject !== "string" ||
        !req.body.subject.trim()
      ) {
        return res.status(400).json({
          success: false,
          message: "Subject cannot be empty.",
        });
      }
      group.subject = req.body.subject.trim();
    }

    await group.save();
    res.json({ success: true, data: group });
  } catch (error) {
    res.status(400).json({
      success: false,
      message: "Could not update the group.",
    });
  }
});

// Delete a group (login required)
app.delete("/api/groups/:id", requireAuth, async (req, res) => {
  try {
    const group = await Group.findById(req.params.id);

    if (!group) {
      return res.status(404).json({
        success: false,
        message: "Study group not found.",
      });
    }

    if (!(await canManageGroup(group, req.userId))) {
      return res.status(403).json({
        success: false,
        message: "You cannot delete this group.",
      });
    }

    await Promise.all([
      GroupMember.deleteMany({ groupId: group._id }),
      StudySession.deleteMany({ groupId: group._id }),
      group.deleteOne(),
    ]);

    res.json({ success: true, message: "Study group deleted." });
  } catch (error) {
    res.status(400).json({
      success: false,
      message: "Could not delete the group.",
    });
  }
});

// ---------- GROUP MEMBERS ----------

// List members
app.get(
  "/api/groups/:id/members",
  requireAuth,
  async (req, res) => {
    try {
      const group = await Group.findById(req.params.id);
      if (!group) {
        return res.status(404).json({
          success: false,
          message: "Study group not found.",
        });
      }

      const members = await GroupMember.find({
        groupId: group._id,
      }).sort({ createdAt: 1 });

      res.json({ success: true, data: members });
    } catch {
      res.status(400).json({
        success: false,
        message: "Could not load members.",
      });
    }
  }
);

// Add a member
app.post(
  "/api/groups/:id/members",
  requireAuth,
  async (req, res) => {
    try {
      const group = await Group.findById(req.params.id);
      if (!group) {
        return res.status(404).json({
          success: false,
          message: "Study group not found.",
        });
      }

      if (!(await canManageGroup(group, req.userId))) {
        return res.status(403).json({
          success: false,
          message: "You cannot manage this group's members.",
        });
      }

      const name = req.body.name?.trim();
      const email = req.body.email?.trim().toLowerCase();

      if (!name || !email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({
          success: false,
          message: "Enter a member name and valid email.",
        });
      }

      const member = await GroupMember.create({
        groupId: group._id,
        name,
        email,
      });

      group.members = 1 + await GroupMember.countDocuments({
        groupId: group._id,
      });
      await group.save();

      res.status(201).json({ success: true, data: member });
    } catch (error) {
      if (error.code === 11000) {
        return res.status(409).json({
          success: false,
          message: "That email is already listed in this group.",
        });
      }

      res.status(400).json({
        success: false,
        message: "Could not add member.",
      });
    }
  }
);

// Remove a member
app.delete(
  "/api/groups/:id/members/:memberId",
  requireAuth,
  async (req, res) => {
    try {
      const group = await Group.findById(req.params.id);
      if (!group) {
        return res.status(404).json({
          success: false,
          message: "Study group not found.",
        });
      }

      if (!(await canManageGroup(group, req.userId))) {
        return res.status(403).json({
          success: false,
          message: "You cannot manage this group's members.",
        });
      }

      const member = await GroupMember.findOneAndDelete({
        _id: req.params.memberId,
        groupId: group._id,
      });

      if (!member) {
        return res.status(404).json({
          success: false,
          message: "Member not found.",
        });
      }

      group.members = 1 + await GroupMember.countDocuments({
        groupId: group._id,
      });
      await group.save();

      res.json({ success: true, message: "Member removed." });
    } catch {
      res.status(400).json({
        success: false,
        message: "Could not remove member.",
      });
    }
  }
);

// ---------- STUDY SESSIONS ----------

// List scheduled sessions
app.get("/api/sessions", requireAuth, async (req, res) => {
  try {
    const sessions = await StudySession.find()
      .populate("groupId", "name subject")
      .sort({ startAt: 1 });

    res.json({ success: true, data: sessions });
  } catch {
    res.status(500).json({
      success: false,
      message: "Could not load study sessions.",
    });
  }
});

// Schedule a session
app.post("/api/sessions", requireAuth, async (req, res) => {
  try {
    const { title, subject, groupId, startAt, location, meetingLink } =
      req.body;

    if (
      !title?.trim() ||
      !subject?.trim() ||
      !mongoose.isValidObjectId(groupId) ||
      !startAt ||
      Number.isNaN(Date.parse(startAt))
    ) {
      return res.status(400).json({
        success: false,
        message: "Enter a title, subject, group, and valid date/time.",
      });
    }

    const group = await Group.findById(groupId);
    if (!group) {
      return res.status(404).json({
        success: false,
        message: "Study group not found.",
      });
    }

    if (
      meetingLink &&
      (!/^https?:\/\//i.test(meetingLink) || meetingLink.length > 500)
    ) {
      return res.status(400).json({
        success: false,
        message: "Meeting links must start with http:// or https://.",
      });
    }

    const session = await StudySession.create({
      title: title.trim(),
      subject: subject.trim(),
      groupId: group._id,
      createdBy: req.userId,
      startAt: new Date(startAt),
      location: location?.trim() || "",
      meetingLink: meetingLink?.trim() || "",
    });

    res.status(201).json({ success: true, data: session });
  } catch {
    res.status(400).json({
      success: false,
      message: "Could not schedule the study session.",
    });
  }
});

// Delete a scheduled session (only its creator can delete it)
app.delete("/api/sessions/:id", requireAuth, async (req, res) => {
  try {
    const session = await StudySession.findOneAndDelete({
      _id: req.params.id,
      createdBy: req.userId,
    });

    if (!session) {
      return res.status(404).json({
        success: false,
        message: "Session not found or you cannot delete it.",
      });
    }

    res.json({ success: true, message: "Session cancelled." });
  } catch {
    res.status(400).json({
      success: false,
      message: "Could not cancel the session.",
    });
  }
});

// ---------- START SERVER ----------

const PORT = process.env.PORT || 5000;

async function startServer() {
  if (
    !process.env.MONGODB_URI ||
    !process.env.JWT_SECRET ||
    process.env.JWT_SECRET.length < 32
  ) {
    console.error(
      "Set MONGODB_URI and a JWT_SECRET of at least 32 characters in .env."
    );
    process.exitCode = 1;
    return;
  }

  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log("Connected to MongoDB successfully.");

    app.listen(PORT, () => {
      console.log(`Backend running at http://localhost:${PORT}`);
    });
  } catch (error) {
    console.error("Could not start the backend:", error.message);
    process.exitCode = 1;
  }
}

startServer();
